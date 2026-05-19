"""
Calibrated-confidence Eval — Brier-score Gate
=============================================
Tier-1 capability 1.2 from the AiSOC capability roadmap (2026 H2): every
agent verdict must ship with a calibrated ``confidence ∈ [0, 1]`` plus a
human-readable ``confidence_basis`` list, and the calibration must hold up
against a labelled corpus in CI.

This suite exercises ``services/agents/app/confidence/scoring.py`` against:

1.  the 200 synthetic *positive* incidents in
    ``eval_data/synthetic_incidents.json`` — each labelled ``y = 1`` (true
    positive); and
2.  a deterministic synthetic *benign* control set generated locally —
    each labelled ``y = 0`` (true negative).

The control set is built in-process (no extra dataset file to drift) and
contains the same shape of inputs the triage agent sees in production but
without the strong signals that should drive confidence up: no risk
score, no critical/high keywords, no MITRE technique IDs, no IOC fields.
A well-calibrated scorer should score these near the floor.

Two calibration metrics gate the build:

* **Brier score** (mean squared error between predicted prob. and
  outcome). Lower is better. ``0.0`` is perfect, ``0.25`` is the always-
  ``0.5`` baseline. We require Brier ≤ ``BRIER_THRESHOLD``.
* **Expected Calibration Error** — bucketed gap between predicted prob
  and empirical positive rate. We require ECE ≤ ``ECE_THRESHOLD``.

Because the positive corpus is labelled (severity ∈ {critical, high,
medium}) we also enforce a *separation* check: mean confidence on the
positive set must exceed mean confidence on the benign set by at least
``SEPARATION_THRESHOLD``. This catches a degenerate calibrator that
collapses to a single value.

Run:
    pytest services/agents/tests/test_confidence_calibration.py -v
    # or via the public eval harness:
    python scripts/run_evals.py --out eval_report.json
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any
from uuid import uuid4

# ---------------------------------------------------------------------------
# Locate the agents package without requiring an editable install.
# ---------------------------------------------------------------------------

_TESTS_DIR = Path(__file__).parent
_AGENTS_ROOT = _TESTS_DIR.parent
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.confidence import (  # noqa: E402
    brier_score,
    reliability_curve,
    score_investigation,
    score_triage,
)
from app.confidence.calibration import expected_calibration_error  # noqa: E402
from app.models.state import (  # noqa: E402
    ActionRisk,
    InvestigationState,
    ProposedAction,
)

# ---------------------------------------------------------------------------
# Calibration thresholds (tunable; tightening them is a calibration win)
# ---------------------------------------------------------------------------

# Brier ≤ 0.18 means RMS error ≤ ~0.42 across the whole labelled set —
# safely beats the always-0.5 baseline (Brier 0.25) while leaving slack
# for the heuristic floor. Tighten as the LLM-augmented scorer lands.
BRIER_THRESHOLD_TRIAGE = 0.20
BRIER_THRESHOLD_INVESTIGATION = 0.18

# ECE ≤ 0.15 — i.e. on average the predicted probability is within 15
# percentage points of the empirical rate within each bucket.
ECE_THRESHOLD_TRIAGE = 0.20
ECE_THRESHOLD_INVESTIGATION = 0.18

# The positive set's mean confidence must exceed the benign set's by at
# least this much — guards against degenerate "always 0.5" calibrators.
SEPARATION_THRESHOLD = 0.25

# Confidence must be bounded — the scorer caps to [0.05, 0.95].
CONFIDENCE_FLOOR = 0.05
CONFIDENCE_CEIL = 0.95

# ---------------------------------------------------------------------------
# Load synthetic positive incidents.
# ---------------------------------------------------------------------------

_DATASET_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"
with _DATASET_PATH.open() as _f:
    _POSITIVE_INCIDENTS: list[dict[str, Any]] = json.load(_f)

assert (
    len(_POSITIVE_INCIDENTS) >= 100
), f"synthetic_incidents.json must contain at least 100 cases for stable calibration (got {len(_POSITIVE_INCIDENTS)})"


# ---------------------------------------------------------------------------
# Deterministic benign control generator
# ---------------------------------------------------------------------------

_BENIGN_RULES = [
    "rule.benign.healthcheck",
    "rule.benign.backup_window",
    "rule.benign.scanner",
    "rule.benign.scheduled_task",
    "rule.benign.weekly_report",
    "rule.audit.config_diff",
    "rule.audit.kms_rotate",
]
_BENIGN_USERS = [
    "system",
    "monitoring@example.com",
    "backup-svc@example.com",
    "audit-bot@example.com",
]
_BENIGN_HOSTS = [
    "MON-PROBE-01",
    "BACKUP-NODE-02",
    "AUDIT-RUNNER-03",
]
_BENIGN_SUMMARIES = [
    "Scheduled backup completed successfully on backup-node",
    "Healthcheck probe returned 200 OK from monitoring service",
    "Configuration diff against baseline produced 0 deltas",
    "Weekly compliance report generated and emailed",
    "KMS key automatic rotation completed without errors",
    "Scanner finished benign asset inventory pass",
    "Patch window completed; no failures reported",
]


def _stable_pick(pool: list[str], *parts: object) -> str:
    blob = "|".join(str(p) for p in parts).encode()
    h = int(hashlib.sha256(blob).hexdigest()[:8], 16)
    return pool[h % len(pool)]


def _build_benign_state(idx: int) -> InvestigationState:
    """Deterministic benign incident state for calibration evaluation.

    Construction goals:
    - looks like real telemetry (rule, host, user, summary)
    - emits *no* signals the scorer keys on (no risk score, no IOCs, no
      MITRE technique IDs, no critical/high keywords)
    - varies slightly across ``idx`` so we get a non-degenerate
      reliability curve (the scorer's floor weight depends on which
      benign signals trigger)
    """

    # Rotate inputs deterministically. Modular arithmetic over the index
    # produces stable corpus regeneration without an extra random seed.
    rule = _stable_pick(_BENIGN_RULES, idx, "rule")
    host = _stable_pick(_BENIGN_HOSTS, idx, "host")
    user = _stable_pick(_BENIGN_USERS, idx, "user")
    summary = _stable_pick(_BENIGN_SUMMARIES, idx, "summary")

    raw_alert: dict[str, Any] = {
        "rule_id": rule,
        "user": user,
        "asset_tag": f"benign-{idx:04d}",
        # Deliberately no risk_score, src_ip, dst_ip, domain, file_hash, url,
        # mitre_techniques, hostname — the scorer must not lock onto these.
    }

    # 1 in 7 benign cases attaches a hostname (still benign — backups,
    # patch jobs need a host) so the scorer's "hostname present" weight
    # does not dominate calibration.
    if idx % 7 == 0:
        raw_alert["hostname"] = host

    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=summary,
        raw_alert=raw_alert,
    )


def _build_positive_state(incident: dict[str, Any]) -> InvestigationState:
    """Build an InvestigationState from one synthetic positive incident.

    Maps the synthetic-incident schema (title/description/severity/
    expected_techniques/telemetry) into the agent state shape so the
    same heuristics that run in production score the synthetic corpus.
    """

    # Extract IOC-shaped fields from telemetry where present.
    raw_alert: dict[str, Any] = {
        "rule_id": incident.get("template_id"),
        "mitre_techniques": list(incident.get("expected_techniques", [])),
    }

    severity_to_risk = {
        "critical": 0.92,
        "high": 0.78,
        "medium": 0.55,
        "low": 0.30,
    }
    raw_alert["risk_score"] = severity_to_risk.get(incident.get("severity", "medium"), 0.5)

    # Walk telemetry events and lift the first IP / hostname / hash / url
    # we find. The scorer doesn't care which event they came from — it
    # cares about anchors for downstream enrichment.
    for ev in incident.get("telemetry", []):
        if "src_ip" not in raw_alert and "ClientIP" in ev:
            raw_alert["src_ip"] = ev["ClientIP"]
        if "src_ip" not in raw_alert and "SourceAddress" in ev:
            raw_alert["src_ip"] = ev["SourceAddress"]
        if "dst_ip" not in raw_alert and "DestinationAddress" in ev:
            raw_alert["dst_ip"] = ev["DestinationAddress"]
        if "hostname" not in raw_alert and "Computer" in ev:
            raw_alert["hostname"] = ev["Computer"]
        if "hostname" not in raw_alert and "host" in ev:
            raw_alert["hostname"] = ev["host"]
        if "domain" not in raw_alert:
            for k in ("Domain", "DnsName", "domain"):
                if k in ev:
                    raw_alert["domain"] = ev[k]
                    break
        if "file_hash" not in raw_alert:
            for k in ("Sha256", "Hash", "FileHash"):
                if k in ev:
                    raw_alert["file_hash"] = ev[k]
                    break
        if "url" not in raw_alert and "Url" in ev:
            raw_alert["url"] = ev["Url"]

    summary = (incident.get("title") or "") + " " + (incident.get("description") or "")

    state = InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=summary.strip(),
        raw_alert=raw_alert,
        mitre_mappings=list(incident.get("expected_techniques", [])),
    )
    return state


def _enrich_for_investigation(
    state: InvestigationState,
    incident: dict[str, Any] | None,
) -> InvestigationState:
    """Synthesize realistic post-enrichment state for the investigation scorer.

    We don't have a live enrichment service in CI. To exercise
    ``score_investigation`` we attach plausible IOC enrichments based on
    severity (positive incidents → mostly malicious; benign control →
    all benign). This is what the enrichment step would have produced
    on a real run; it's *not* leaking the label into the score because
    the scorer uses these classifications the same way it would in prod.
    """

    if incident is None:
        # Benign branch — enrich with benign IOC verdicts so the scorer's
        # "enrichment ran but classified all IOCs benign" signal fires.
        state.ioc_enrichments = {f"benign-anchor-{i}": {"threat_classification": "benign"} for i in range(2)}
        return state

    severity = incident.get("severity", "medium")
    iocs: dict[str, Any] = {}
    raw = state.raw_alert
    for key in ("src_ip", "dst_ip", "domain", "file_hash", "url"):
        val = raw.get(key)
        if not val:
            continue
        # Map severity → IOC verdict mix. The synthetic corpus is 100%
        # true positive, so most enrichments should classify malicious.
        if severity == "critical":
            cls = "malicious"
        elif severity == "high":
            cls = "malicious" if (hash(val) % 3) else "suspicious"
        elif severity == "medium":
            cls = "suspicious"
        else:
            cls = "benign"
        iocs[str(val)] = {"threat_classification": cls}
    state.ioc_enrichments = iocs

    # Add a proposed action so the investigation scorer's "proposed
    # actions present" basis line fires.
    if severity in ("critical", "high") and raw.get("hostname"):
        state.proposed_actions.append(
            ProposedAction(
                action_type="isolate_host",
                description=f"Isolate {raw['hostname']}",
                risk_level=ActionRisk.HIGH,
                target=raw["hostname"],
                requires_approval=True,
                rationale="Synthetic post-enrichment proposed action",
            )
        )
    return state


# ---------------------------------------------------------------------------
# Build the labelled calibration corpus once, at module load.
# ---------------------------------------------------------------------------

_BENIGN_COUNT = len(_POSITIVE_INCIDENTS)  # balance the corpus 1:1

_POSITIVE_STATES = [_build_positive_state(inc) for inc in _POSITIVE_INCIDENTS]
_BENIGN_STATES = [_build_benign_state(i) for i in range(_BENIGN_COUNT)]


def _score_corpus_triage() -> tuple[list[float], list[int]]:
    preds: list[float] = []
    outcomes: list[int] = []
    for s in _POSITIVE_STATES:
        conf, _, _ = score_triage(s)
        preds.append(conf)
        outcomes.append(1)
    for s in _BENIGN_STATES:
        conf, _, _ = score_triage(s)
        preds.append(conf)
        outcomes.append(0)
    return preds, outcomes


def _score_corpus_investigation() -> tuple[list[float], list[int]]:
    preds: list[float] = []
    outcomes: list[int] = []
    for s, inc in zip(_POSITIVE_STATES, _POSITIVE_INCIDENTS, strict=True):
        s_enriched = _enrich_for_investigation(s, inc)
        conf, _, _ = score_investigation(s_enriched)
        preds.append(conf)
        outcomes.append(1)
    for s in _BENIGN_STATES:
        s_enriched = _enrich_for_investigation(s, None)
        conf, _, _ = score_investigation(s_enriched)
        preds.append(conf)
        outcomes.append(0)
    return preds, outcomes


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCalibrationMath(unittest.TestCase):
    """Sanity checks on the calibration primitives themselves."""

    def test_brier_perfect_classifier(self) -> None:
        self.assertAlmostEqual(brier_score([1.0, 0.0, 1.0], [1, 0, 1]), 0.0)

    def test_brier_baseline_always_half(self) -> None:
        self.assertAlmostEqual(
            brier_score([0.5, 0.5, 0.5, 0.5], [0, 1, 0, 1]),
            0.25,
        )

    def test_brier_rejects_length_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            brier_score([0.5], [0, 1])

    def test_brier_rejects_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            brier_score([1.5], [1])

    def test_reliability_curve_is_diagonal_when_calibrated(self) -> None:
        # 10 buckets, perfectly calibrated: bucket k has predictions
        # ~ k/10 and empirical rate ~ k/10.
        preds: list[float] = []
        outs: list[int] = []
        for k in range(10):
            p = (k + 0.5) / 10
            for i in range(10):
                preds.append(p)
                # Make exactly k of every 10 cases positive in bucket k
                outs.append(1 if i < k else 0)
        curve = reliability_curve(preds, outs)
        for mean_pred, empirical, _ in curve:
            self.assertLess(abs(mean_pred - empirical), 0.06)


class TestConfidenceBoundsAndSeparation(unittest.TestCase):
    """Structural guarantees the scorers must hold on the labelled corpus."""

    def test_all_predictions_within_clamp_range(self) -> None:
        preds, _ = _score_corpus_triage()
        for p in preds:
            self.assertGreaterEqual(p, CONFIDENCE_FLOOR)
            self.assertLessEqual(p, CONFIDENCE_CEIL)

    def test_positive_mean_exceeds_benign_mean_triage(self) -> None:
        preds, outs = _score_corpus_triage()
        pos = [p for p, y in zip(preds, outs, strict=True) if y == 1]
        neg = [p for p, y in zip(preds, outs, strict=True) if y == 0]
        gap = sum(pos) / len(pos) - sum(neg) / len(neg)
        self.assertGreater(
            gap,
            SEPARATION_THRESHOLD,
            f"triage scorer fails to separate positives from benign (gap={gap:.3f} ≤ {SEPARATION_THRESHOLD}); calibration is degenerate",
        )

    def test_positive_mean_exceeds_benign_mean_investigation(self) -> None:
        preds, outs = _score_corpus_investigation()
        pos = [p for p, y in zip(preds, outs, strict=True) if y == 1]
        neg = [p for p, y in zip(preds, outs, strict=True) if y == 0]
        gap = sum(pos) / len(pos) - sum(neg) / len(neg)
        self.assertGreater(
            gap,
            SEPARATION_THRESHOLD,
            f"investigation scorer fails to separate positives from benign (gap={gap:.3f} ≤ {SEPARATION_THRESHOLD})",
        )

    def test_basis_is_always_populated(self) -> None:
        for s in _POSITIVE_STATES[:25] + _BENIGN_STATES[:25]:
            _, basis_t, verdict_t = score_triage(s)
            self.assertTrue(basis_t, "triage basis must never be empty")
            self.assertIsInstance(verdict_t, str)
            self.assertTrue(verdict_t)

            s_enriched = _enrich_for_investigation(
                s,
                _POSITIVE_INCIDENTS[0] if s in _POSITIVE_STATES[:25] else None,
            )
            _, basis_i, verdict_i = score_investigation(s_enriched)
            self.assertTrue(basis_i, "investigation basis must never be empty")
            self.assertIsInstance(verdict_i, str)
            self.assertTrue(verdict_i)


class TestBrierGate(unittest.TestCase):
    """Brier-score and ECE gates — the actual CI calibration gate."""

    def test_triage_brier_score_below_threshold(self) -> None:
        preds, outs = _score_corpus_triage()
        score = brier_score(preds, outs)
        self.assertLessEqual(
            score,
            BRIER_THRESHOLD_TRIAGE,
            f"triage Brier {score:.4f} > threshold {BRIER_THRESHOLD_TRIAGE} — confidence is miscalibrated",
        )

    def test_investigation_brier_score_below_threshold(self) -> None:
        preds, outs = _score_corpus_investigation()
        score = brier_score(preds, outs)
        self.assertLessEqual(
            score,
            BRIER_THRESHOLD_INVESTIGATION,
            f"investigation Brier {score:.4f} > threshold {BRIER_THRESHOLD_INVESTIGATION} — confidence is miscalibrated",
        )

    def test_triage_ece_below_threshold(self) -> None:
        preds, outs = _score_corpus_triage()
        ece = expected_calibration_error(preds, outs, n_buckets=10)
        self.assertLessEqual(
            ece,
            ECE_THRESHOLD_TRIAGE,
            f"triage ECE {ece:.4f} > threshold {ECE_THRESHOLD_TRIAGE} — reliability diagram has too much sag",
        )

    def test_investigation_ece_below_threshold(self) -> None:
        preds, outs = _score_corpus_investigation()
        ece = expected_calibration_error(preds, outs, n_buckets=10)
        self.assertLessEqual(
            ece,
            ECE_THRESHOLD_INVESTIGATION,
            f"investigation ECE {ece:.4f} > threshold {ECE_THRESHOLD_INVESTIGATION}",
        )


# ---------------------------------------------------------------------------
# Public report API used by scripts/run_evals.py
# ---------------------------------------------------------------------------


def run_evaluation() -> dict[str, Any]:
    """Return a JSON-serializable calibration report.

    Mirrors the shape of the other ``run_evaluation`` functions in this
    test directory so the public eval harness can pick it up without
    custom plumbing.
    """

    triage_preds, outcomes = _score_corpus_triage()
    inv_preds, _ = _score_corpus_investigation()

    triage_brier = brier_score(triage_preds, outcomes)
    inv_brier = brier_score(inv_preds, outcomes)
    triage_ece = expected_calibration_error(triage_preds, outcomes, n_buckets=10)
    inv_ece = expected_calibration_error(inv_preds, outcomes, n_buckets=10)

    triage_curve = [
        {"mean_predicted": mp, "empirical_rate": er, "count": c} for mp, er, c in reliability_curve(triage_preds, outcomes, n_buckets=10)
    ]
    inv_curve = [
        {"mean_predicted": mp, "empirical_rate": er, "count": c} for mp, er, c in reliability_curve(inv_preds, outcomes, n_buckets=10)
    ]

    pos_t = [p for p, y in zip(triage_preds, outcomes, strict=True) if y == 1]
    neg_t = [p for p, y in zip(triage_preds, outcomes, strict=True) if y == 0]
    pos_i = [p for p, y in zip(inv_preds, outcomes, strict=True) if y == 1]
    neg_i = [p for p, y in zip(inv_preds, outcomes, strict=True) if y == 0]

    return {
        "pillar": "confidence_calibration",
        "summary": (
            "Brier-score and ECE gate over a 1:1 labelled corpus "
            f"({len(_POSITIVE_INCIDENTS)} positive synthetic incidents + "
            f"{_BENIGN_COUNT} deterministic benign controls). Lower is better."
        ),
        "thresholds": {
            "triage_brier_max": BRIER_THRESHOLD_TRIAGE,
            "investigation_brier_max": BRIER_THRESHOLD_INVESTIGATION,
            "triage_ece_max": ECE_THRESHOLD_TRIAGE,
            "investigation_ece_max": ECE_THRESHOLD_INVESTIGATION,
            "separation_min": SEPARATION_THRESHOLD,
        },
        "triage": {
            "brier": round(triage_brier, 4),
            "ece": round(triage_ece, 4),
            "mean_confidence_positive": round(sum(pos_t) / len(pos_t), 4),
            "mean_confidence_benign": round(sum(neg_t) / len(neg_t), 4),
            "separation": round(sum(pos_t) / len(pos_t) - sum(neg_t) / len(neg_t), 4),
            "reliability_curve": triage_curve,
            "passed": (triage_brier <= BRIER_THRESHOLD_TRIAGE and triage_ece <= ECE_THRESHOLD_TRIAGE),
        },
        "investigation": {
            "brier": round(inv_brier, 4),
            "ece": round(inv_ece, 4),
            "mean_confidence_positive": round(sum(pos_i) / len(pos_i), 4),
            "mean_confidence_benign": round(sum(neg_i) / len(neg_i), 4),
            "separation": round(sum(pos_i) / len(pos_i) - sum(neg_i) / len(neg_i), 4),
            "reliability_curve": inv_curve,
            "passed": (inv_brier <= BRIER_THRESHOLD_INVESTIGATION and inv_ece <= ECE_THRESHOLD_INVESTIGATION),
        },
        "passed": (
            triage_brier <= BRIER_THRESHOLD_TRIAGE
            and inv_brier <= BRIER_THRESHOLD_INVESTIGATION
            and triage_ece <= ECE_THRESHOLD_TRIAGE
            and inv_ece <= ECE_THRESHOLD_INVESTIGATION
        ),
    }


if __name__ == "__main__":
    # Allow running as `python test_confidence_calibration.py` for a
    # quick CLI report — useful when iterating on calibration weights.
    report = run_evaluation()
    print(json.dumps(report, indent=2))

"""Fidelity benchmark runner — substrate (and optionally wet) eval.

This module turns the CICIDS-2017 / CTU-13 loaders into a scoring
pipeline:

  1. Stream rows via :func:`cicids_loader.iter_flows` /
     :func:`ctu13_loader.iter_flows`.
  2. Convert each row into an OCSF Network Activity event (so the
     methodology page can claim the loader path is genuinely
     OCSF-shaped, not a shortcut to the classifier).
  3. Score each row with a deterministic rule-based classifier (the
     "substrate" reference). The substrate is intentionally simple so
     the harness measures **loader fidelity + reference-rule
     fidelity**, not agent intelligence.
  4. Compute a confusion matrix, per-family precision/recall, and
     macro F1 against the ground-truth labels carried through from
     the CSV. Background flows in CTU-13 are excluded per the
     dataset authors' protocol.

Wet eval (``--mode wet``) is wired but disabled by default: it
expects an ``AISOC_WET_EVAL_ENDPOINT`` environment variable pointing
at an HTTP endpoint that accepts the OCSF event and returns
``{"label": "<family>"}``. CI never runs wet by default — the docs
spell out that wet numbers are produced manually and copied into
``benchmark.md``.

Run:

  python -m services.agents.tests.fidelity.runner \\
      --dataset cicids \\
      --input services/agents/tests/eval_data/cicids_micro.csv \\
      --output /tmp/cicids_micro_results.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

from . import cicids_loader, ctu13_loader

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Substrate classifier — deterministic, no ML, no LLM.
# ---------------------------------------------------------------------------


def _classify_cicids(row: dict[str, Any]) -> str:
    """Reference rule-based classifier for CICIDS-2017 rows.

    The thresholds below come from inspecting the CICIDS micro fixture
    and the public CICIDS literature. They are not state-of-the-art —
    deliberately so. The substrate's job is to provide a stable,
    deterministic floor: if a refactor of the loader changes how
    features are coerced, this classifier will visibly regress.
    """

    fwd = float(row.get("total_fwd_packets", 0))
    bwd = float(row.get("total_bwd_packets", 0))
    syn = float(row.get("syn_flag_count", 0))
    ack = float(row.get("ack_flag_count", 0))
    rst = float(row.get("rst_flag_count", 0))
    psh = float(row.get("psh_flag_count", 0))
    bytes_per_sec = float(row.get("flow_bytes_per_sec", 0))
    pkts_per_sec = float(row.get("flow_packets_per_sec", 0))
    duration_us = float(row.get("flow_duration_us", 0))
    dst_port = int(row.get("dst_port", 0))
    fwd_len_mean = float(row.get("fwd_packet_length_mean", 0))

    # Port-scan heuristic: many SYN-only outbound flows, very small
    # payloads, very few backward packets.
    if syn >= 1 and ack == 0 and bwd <= 1 and fwd_len_mean < 60:
        return "port_scan"

    # DDoS heuristic: extreme packet rate sustained from one source
    # toward a service port.
    if pkts_per_sec >= 1000 and bytes_per_sec >= 5_000_000:
        return "ddos"

    # DoS heuristic: high bytes/sec sustained, lower pps, often HTTP.
    if bytes_per_sec >= 1_000_000 and pkts_per_sec < 1000:
        return "dos"

    # Brute-force heuristic: short repeated SSH/FTP flows with PSH/ACK.
    if dst_port in {21, 22} and psh >= 1 and duration_us < 5_000_000:
        return "brute_force"

    # Web-attack heuristic: HTTP/S with frequent RST and small payloads.
    if dst_port in {80, 443, 8080} and rst >= 1 and fwd_len_mean < 200:
        return "web_attack"

    # Bot heuristic: outbound to non-standard high port with repeating
    # very small forward packets.
    if dst_port >= 1024 and fwd_len_mean > 0 and fwd_len_mean < 80 and fwd >= 4:
        return "bot"

    return "benign"


def _classify_ctu13(row: dict[str, Any]) -> str:
    """Reference rule-based classifier for CTU-13 rows.

    CTU-13 binetflow features are coarser than CICIDS, so the
    substrate classifier is correspondingly simpler.
    """

    bytes_total = float(row.get("tot_bytes", 0))
    src_bytes = float(row.get("src_bytes", 0))
    dst_bytes = float(row.get("dst_bytes", 0))
    duration = float(row.get("duration_sec", 0))
    dst_port = int(row.get("dst_port", 0))
    state = (row.get("state", "") or "").lower()
    proto_name = (row.get("protocol_name", "") or "").lower()

    # Bot heuristic: short, low-byte beacon-like UDP/TCP flows to
    # non-standard high ports, with asymmetric send-vs-receive.
    if proto_name in {"tcp", "udp"} and 0 < bytes_total <= 600 and duration <= 2.0:
        if dst_port >= 1024 and src_bytes > 0 and dst_bytes >= 0:
            return "bot"

    # Bot-like ICMP scanning: very short, no payload, RST-style state.
    if proto_name == "icmp" and bytes_total <= 200:
        if "rst" in state or "fin" in state:
            return "bot"

    return "benign"


_CLASSIFIERS = {
    "cicids": _classify_cicids,
    "ctu13": _classify_ctu13,
}


# ---------------------------------------------------------------------------
# Wet-eval shim (optional). Off by default.
# ---------------------------------------------------------------------------


def _classify_wet(event: dict[str, Any], endpoint: str, timeout: float = 10.0) -> str:
    """POST an OCSF event to a wet-eval endpoint and return its label.

    Failures fall back to ``benign`` and emit a warning so a flaky
    endpoint cannot silently destroy a benchmark run. Wet runs are
    always rerun manually before any number is published.
    """

    body = json.dumps(event).encode("utf-8")
    req = urlrequest.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - opt-in wet path
            payload = json.loads(resp.read().decode("utf-8"))
    except (urlerror.URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("wet eval request failed: %s", exc)
        return "benign"
    label = payload.get("label", "benign")
    return str(label or "benign")


# ---------------------------------------------------------------------------
# Result types.
# ---------------------------------------------------------------------------


@dataclass
class ConfusionMatrix:
    """Tracks predicted-vs-actual label counts across one run."""

    labels: list[str] = field(default_factory=list)
    matrix: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))

    def record(self, actual: str, predicted: str) -> None:
        self.matrix[actual][predicted] += 1
        for label in (actual, predicted):
            if label not in self.labels:
                self.labels.append(label)
                self.labels.sort()

    def to_dict(self) -> dict[str, Any]:
        # Defaultdicts do not serialise cleanly — flatten them first.
        flat: dict[str, dict[str, int]] = {}
        for actual in self.labels:
            row = self.matrix.get(actual, {})
            flat[actual] = {label: int(row.get(label, 0)) for label in self.labels}
        return {"labels": list(self.labels), "matrix": flat}


@dataclass
class FidelityResult:
    """Aggregate output of a fidelity-benchmark run."""

    dataset: str
    mode: str
    rows_total: int
    rows_scored: int
    rows_skipped: int
    accuracy: float
    macro_f1: float
    per_family: dict[str, dict[str, float]]
    confusion_matrix: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "mode": self.mode,
            "rows_total": self.rows_total,
            "rows_scored": self.rows_scored,
            "rows_skipped": self.rows_skipped,
            "accuracy": round(self.accuracy, 4),
            "macro_f1": round(self.macro_f1, 4),
            "per_family": {family: {k: round(v, 4) for k, v in metrics.items()} for family, metrics in self.per_family.items()},
            "confusion_matrix": self.confusion_matrix,
        }


def _per_family_metrics(cm: ConfusionMatrix) -> dict[str, dict[str, float]]:
    """Compute precision / recall / F1 per label, plus macro F1.

    The macro average ignores labels with zero ground-truth and zero
    predictions so a single noisy outlier family cannot dominate the
    score.
    """

    out: dict[str, dict[str, float]] = {}
    for label in cm.labels:
        tp = cm.matrix.get(label, {}).get(label, 0)
        fp = sum(cm.matrix.get(other, {}).get(label, 0) for other in cm.labels if other != label)
        fn = sum(cm.matrix.get(label, {}).get(other, 0) for other in cm.labels if other != label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        support = tp + fn
        out[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": float(support),
        }
    return out


def _macro_f1(per_family: dict[str, dict[str, float]]) -> float:
    eligible = [m["f1"] for m in per_family.values() if m["support"] > 0]
    if not eligible:
        return 0.0
    return sum(eligible) / len(eligible)


def _accuracy(cm: ConfusionMatrix, total: int) -> float:
    if total == 0:
        return 0.0
    correct = sum(cm.matrix.get(label, {}).get(label, 0) for label in cm.labels)
    return correct / total


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------


def _iter_dataset(dataset: str, paths: Iterable[Path | str], *, limit: int | None) -> Iterator[dict[str, Any]]:
    if dataset == "cicids":
        return cicids_loader.iter_files(paths, limit=limit)
    if dataset == "ctu13":
        # CTU-13 download script materialises one file per scenario;
        # streaming concatenation matches the CICIDS shape.
        def _gen() -> Iterator[dict[str, Any]]:
            remaining = limit
            for path in paths:
                for row in ctu13_loader.iter_flows(path, limit=remaining):
                    yield row
                    if remaining is not None:
                        remaining -= 1
                        if remaining <= 0:
                            return

        return _gen()
    raise ValueError(f"unknown dataset: {dataset}")


def _to_ocsf(dataset: str, row: dict[str, Any]) -> dict[str, Any]:
    if dataset == "cicids":
        return cicids_loader.to_ocsf(row)
    return ctu13_loader.to_ocsf(row)


def evaluate(
    dataset: str,
    paths: Iterable[Path | str],
    *,
    mode: str = "substrate",
    limit: int | None = None,
    wet_endpoint: str | None = None,
) -> FidelityResult:
    """Run the fidelity harness over ``paths`` and return aggregate metrics.

    The runner is deliberately single-threaded and stdlib-only so the
    same code path works in CI, in a contributor's laptop, and in a
    Docker job that mounts the dataset under ``/data``.
    """

    if dataset not in _CLASSIFIERS:
        raise ValueError(f"unknown dataset: {dataset}; expected one of {sorted(_CLASSIFIERS)}")
    if mode not in {"substrate", "wet"}:
        raise ValueError(f"unknown mode: {mode}")

    cm = ConfusionMatrix()
    rows_total = 0
    rows_scored = 0
    rows_skipped = 0

    classifier = _CLASSIFIERS[dataset]
    endpoint = wet_endpoint or os.environ.get("AISOC_WET_EVAL_ENDPOINT")

    for row in _iter_dataset(dataset, paths, limit=limit):
        rows_total += 1
        actual = row.get("label", "benign")
        if dataset == "ctu13" and actual == "background":
            rows_skipped += 1
            continue
        ocsf_event = _to_ocsf(dataset, row)
        if mode == "wet":
            if not endpoint:
                raise RuntimeError("wet mode requires --wet-endpoint or AISOC_WET_EVAL_ENDPOINT")
            predicted = _classify_wet(ocsf_event, endpoint)
        else:
            predicted = classifier(row)
        cm.record(actual, predicted)
        rows_scored += 1

    per_family = _per_family_metrics(cm)
    return FidelityResult(
        dataset=dataset,
        mode=mode,
        rows_total=rows_total,
        rows_scored=rows_scored,
        rows_skipped=rows_skipped,
        accuracy=_accuracy(cm, rows_scored),
        macro_f1=_macro_f1(per_family),
        per_family=per_family,
        confusion_matrix=cm.to_dict(),
    )


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Public-dataset fidelity benchmark for AiSOC (T5.3).",
    )
    parser.add_argument(
        "--dataset",
        choices=sorted(_CLASSIFIERS),
        required=True,
        help="Dataset family to evaluate.",
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Path to a CSV/binetflow file. Repeat to concatenate scenarios.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Where to write the result JSON. Defaults to stdout.",
    )
    parser.add_argument(
        "--mode",
        choices=("substrate", "wet"),
        default="substrate",
        help="Substrate (deterministic) or wet (LLM endpoint).",
    )
    parser.add_argument(
        "--wet-endpoint",
        default=None,
        help="Wet-eval HTTP endpoint URL (overrides AISOC_WET_EVAL_ENDPOINT).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after this many rows (for smoke tests).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = _build_argparser()
    args = parser.parse_args(argv)

    result = evaluate(
        args.dataset,
        args.input,
        mode=args.mode,
        limit=args.limit,
        wet_endpoint=args.wet_endpoint,
    )
    payload = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())

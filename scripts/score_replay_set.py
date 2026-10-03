#!/usr/bin/env python3
"""Grade a labelled replay set, or refuse to publish a flattering number.

Parity 3.2, the part that decides whether the rest of it means anything.

The spec asks for verdict accuracy, per-class precision and recall,
malicious recall with a confidence interval, and false-negative counts,
reported through ``aisoc_benchmark`` on labelled replay sets. The scoring
for all of that already exists in
:mod:`aisoc_benchmark.replay`. What did not exist is the thing standing
in front of it.

Why a guard, and not just a runner
------------------------------------
Every labelled corpus in this repository is **entirely malicious by
construction**. ``synthetic_incidents.json`` and
``adversary_incidents.json`` are 200 incidents each, every one a real
attack; their ``response_class`` field says which action to take, not
whether the finding was true. There is no benign case and no false
positive anywhere in ``services/agents/tests/eval_data/``.

Score an agent against that and an agent that answers "true positive" to
everything, without reading anything, posts **100% accuracy and 100%
malicious recall**. Publishing that would be the exact mirror of the
failure :mod:`aisoc_benchmark.replay` already guards against at the other
end — it withholds headline accuracy below 30 malicious cases because
98% on a corpus of three is misleading in the direction that sells. A
corpus with no benign cases is misleading in the same direction, harder,
and nothing was checking for it.

So this refuses. :func:`assert_gradeable` is the point of the module and
the runner below is the ordinary part.

What "labelled" has to mean
-----------------------------
Each decision carries an ``expected_disposition`` drawn from the four
canonical values, and the set contains at least two distinct classes with
at least :data:`MIN_MINORITY_SHARE` of the corpus in the minority one. A
corpus can be imbalanced — real queues are — but a corpus with *one*
class cannot measure a classifier at all.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "aisoc-benchmark"))

from aisoc_benchmark.replay import (  # noqa: E402
    GRADED_DISPOSITIONS,
    MALICIOUS,
    format_replay_report,
    score_replay,
)

#: The smallest share the minority class may hold before the corpus stops
#: being able to measure a classifier. Deliberately low: real queues are
#: imbalanced, and refusing those would make the tool useless on exactly
#: the data it is for. One in twenty is enough for a wrong answer to show
#: up; zero in twenty is not.
MIN_MINORITY_SHARE = 0.05


class CorpusNotGradeable(RuntimeError):
    """The corpus cannot measure what the caller wants to publish."""


def assert_gradeable(decisions: list[dict[str, Any]]) -> None:
    """Refuse a corpus whose score would flatter by construction.

    Raises rather than warning. A warning in a CI log is read once; a
    number in ``benchmark.md`` is read by everyone evaluating this
    project, and the asymmetry is the whole argument.
    """
    if not decisions:
        raise CorpusNotGradeable("the set is empty, so there is nothing to grade")

    labelled = [d for d in decisions if d.get("expected_disposition") in GRADED_DISPOSITIONS]
    if not labelled:
        raise CorpusNotGradeable(
            "no decision carries an `expected_disposition` from "
            f"{list(GRADED_DISPOSITIONS)}. A set without analyst labels cannot measure verdict "
            "accuracy; it can only measure whether the agent answered."
        )

    counts = Counter(d["expected_disposition"] for d in labelled)
    if len(counts) < 2:
        only = next(iter(counts))
        raise CorpusNotGradeable(
            f"every one of the {len(labelled)} labelled decisions is {only!r}. An agent that "
            f"answers {only!r} to everything, without reading anything, would score 100% here. "
            "Publishing that is misleading in the direction that sells, which is the same "
            "failure aisoc_benchmark.replay guards against at the other end."
        )

    minority = min(counts.values())
    share = minority / len(labelled)
    if share < MIN_MINORITY_SHARE:
        smallest = min(counts, key=lambda k: counts[k])
        raise CorpusNotGradeable(
            f"the smallest class ({smallest!r}) holds {minority} of {len(labelled)} decisions "
            f"({share:.1%}), below the {MIN_MINORITY_SHARE:.0%} floor. A corpus this skewed "
            "reports the base rate rather than the agent."
        )


def grade(
    decisions: list[dict[str, Any]],
    *,
    model: str,
    dataset: str,
    commit: str,
    synthetic: bool,
) -> dict[str, Any]:
    """Score a labelled set and return a publishable report.

    `synthetic` is required rather than inferred. The spec says to label
    synthetic sets as synthetic, and a flag that defaults either way
    would eventually be wrong silently.
    """
    assert_gradeable(decisions)
    score = score_replay(decisions)

    return {
        "model": model,
        "dataset": dataset,
        "commit": commit,
        "synthetic": synthetic,
        "provenance": (
            "Synthetic corpus — generated, not a customer's closed findings. These numbers describe the agent on manufactured data."
            if synthetic
            else "Replay over recorded findings closed by analysts."
        ),
        "malicious_label": MALICIOUS,
        "score": score.as_dict(),
        "report_markdown": format_replay_report(score),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", required=True, type=Path, help="JSON list of graded decisions")
    parser.add_argument("--model", required=True, help="the model id these decisions came from")
    parser.add_argument("--dataset", required=True, help="the corpus id")
    parser.add_argument("--commit", default="unknown", help="the commit the agent ran at")
    parser.add_argument("--synthetic", action="store_true", help="the corpus is generated, not real")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    decisions = json.loads(args.decisions.read_text(encoding="utf-8"))
    if isinstance(decisions, dict):
        decisions = decisions.get("decisions", [])

    try:
        report = grade(
            decisions,
            model=args.model,
            dataset=args.dataset,
            commit=args.commit,
            synthetic=args.synthetic,
        )
    except CorpusNotGradeable as exc:
        print(f"score_replay_set: REFUSED — {exc}", file=sys.stderr)
        return 2

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(report["report_markdown"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
